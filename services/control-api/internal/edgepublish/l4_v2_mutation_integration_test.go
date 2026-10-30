//go:build integration

package edgepublish_test

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestL4V2ContractRealMutationCompilesDistinctTenantAndScope(t *testing.T) {
	edgepublish.CheckL4V2ContractMutationFixture(t, func(pool *pgxpool.Pool, scopeID, userID, subscriptionID, siteID uuid.UUID) int64 {
		service := l4forward.NewService(l4forward.NewStore(pool))
		actor := l4forward.Actor{ScopeID: scopeID, UserID: userID, ScopeKind: "tenant"}
		var sourceRevision int64
		for index, protocol := range []string{"tcp", "udp"} {
			result, err := service.Create(t.Context(), actor, l4forward.CreateRequest{
				Fields: l4forward.Fields{PackageSubscriptionID: new(subscriptionID),
					Name: protocol, Protocol: protocol, ListenAddress: "*", ListenPort: uint16(18443 + index),
					UpstreamAddress: "8.8.8.8", UpstreamPort: 443, ConnectTimeoutMS: 1000,
					ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, Enabled: true},
				IdempotencyKey: "l4-v2-contract-" + protocol, RequestID: uuid.NewString(),
			})
			if err != nil {
				t.Fatalf("real stream creation %s: %v", protocol, err)
			}
			sourceRevision = result.Forward.PublishIntent.ConfigurationSourceRevision
		}
		return sourceRevision
	})
}

func TestL4V2ContractLastListenerLifecycleCapabilities(t *testing.T) {
	for _, operation := range []string{"delete", "disable"} {
		t.Run(operation, func(t *testing.T) {
			edgepublish.CheckL4V2ContractLifecycleFixture(t, func(pool *pgxpool.Pool, scopeID, userID, subscriptionID, siteID uuid.UUID) []func() int64 {
				service := l4forward.NewService(l4forward.NewStore(pool))
				actor := l4forward.Actor{ScopeID: scopeID, UserID: userID, ScopeKind: "tenant"}
				fields := l4forward.Fields{PackageSubscriptionID: new(subscriptionID),
					Name: "lifecycle", Protocol: "tcp", ListenAddress: "*", ListenPort: 18443,
					UpstreamAddress: "8.8.8.8", UpstreamPort: 443, ConnectTimeoutMS: 1000,
					ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, Enabled: true}
				var current l4forward.Forward
				return []func() int64{
					func() int64 {
						result, err := service.Create(t.Context(), actor, l4forward.CreateRequest{
							Fields: fields, IdempotencyKey: "lifecycle-create", RequestID: uuid.NewString(),
						})
						if err != nil {
							t.Fatal(err)
						}
						current = result.Forward
						return current.PublishIntent.ConfigurationSourceRevision
					},
					func() int64 {
						fields.Protocol = "udp"
						result, err := service.Update(t.Context(), actor, l4forward.UpdateRequest{
							ID: current.ID, ExpectedRevision: current.Revision, Fields: fields,
							IdempotencyKey: "lifecycle-protocol", RequestID: uuid.NewString(),
						})
						if err != nil {
							t.Fatal(err)
						}
						current = result.Forward
						return current.PublishIntent.ConfigurationSourceRevision
					},
					func() int64 {
						if operation == "delete" {
							result, err := service.Delete(t.Context(), actor, l4forward.DeleteRequest{
								ID: current.ID, ExpectedRevision: current.Revision,
								IdempotencyKey: "lifecycle-remove", RequestID: uuid.NewString(),
							})
							if err != nil {
								t.Fatal(err)
							}
							return result.PublishIntent.ConfigurationSourceRevision
						}
						fields.Enabled = false
						result, err := service.Update(t.Context(), actor, l4forward.UpdateRequest{
							ID: current.ID, ExpectedRevision: current.Revision, Fields: fields,
							IdempotencyKey: "lifecycle-remove", RequestID: uuid.NewString(),
						})
						if err != nil {
							t.Fatal(err)
						}
						return result.Forward.PublishIntent.ConfigurationSourceRevision
					},
				}
			})
		})
	}
}

func TestL4DrainLimitReachesPublishedStreams(t *testing.T) {
	edgepublish.CheckL4DrainLimitPublication(t, func(pool *pgxpool.Pool, scopeID, userID, subscriptionID, siteID uuid.UUID) int64 {
		service := l4forward.NewService(l4forward.NewStore(pool))
		result, err := service.Create(t.Context(), l4forward.Actor{ScopeID: scopeID, UserID: userID, ScopeKind: "tenant"}, l4forward.CreateRequest{
			Fields: l4forward.Fields{PackageSubscriptionID: new(subscriptionID),
				Name: "drain", Protocol: "tcp", ListenAddress: "*", ListenPort: 18443,
				UpstreamAddress: "8.8.8.8", UpstreamPort: 443, ConnectTimeoutMS: 1000,
				ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, Enabled: true},
			IdempotencyKey: "l4-drain-limit", RequestID: uuid.NewString(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return result.Forward.PublishIntent.ConfigurationSourceRevision
	})
}

func TestL4NewConnRateReachesPublishedStreams(t *testing.T) {
	var streamID uuid.UUID
	var revision int64
	edgepublish.CheckL4NewConnRatePublication(t, func(pool *pgxpool.Pool, scopeID, userID, subscriptionID, siteID uuid.UUID, rate, burst, ban int) int64 {
		service := l4forward.NewService(l4forward.NewStore(pool))
		actor := l4forward.Actor{ScopeID: scopeID, UserID: userID, ScopeKind: "tenant"}
		fields := l4forward.Fields{PackageSubscriptionID: new(subscriptionID),
			Name: "rate", Protocol: "tcp", ListenAddress: "*", ListenPort: 18443,
			UpstreamAddress: "8.8.8.8", UpstreamPort: 443, ConnectTimeoutMS: 1000,
			ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, Enabled: true,
			MaxNewConnectionsPerClientPerSecond: rate, NewConnectionBurst: burst, NewConnectionBanSeconds: ban}
		var result l4forward.WriteResult
		var err error
		if streamID == uuid.Nil {
			result, err = service.Create(t.Context(), actor, l4forward.CreateRequest{Fields: fields,
				IdempotencyKey: "l4-new-conn-rate-create", RequestID: uuid.NewString()})
		} else {
			result, err = service.Update(t.Context(), actor, l4forward.UpdateRequest{ID: streamID, Fields: fields,
				ExpectedRevision: revision, IdempotencyKey: "l4-new-conn-rate-update", RequestID: uuid.NewString()})
		}
		if err != nil {
			t.Fatal(err)
		}
		if result.Forward.MaxNewConnectionsPerClientPerSecond != rate || result.Forward.NewConnectionBurst != burst ||
			result.Forward.NewConnectionBanSeconds != ban {
			t.Fatalf("stored rate = %+v", result.Forward)
		}
		streamID, revision = result.Forward.ID, result.Forward.Revision
		return result.Forward.PublishIntent.ConfigurationSourceRevision
	})
}

func TestL4TOAReachesPublishedStreams(t *testing.T) {
	var streamID uuid.UUID
	var revision int64
	edgepublish.CheckL4TOAPublication(t, func(pool *pgxpool.Pool, scopeID, userID, subscriptionID, siteID uuid.UUID, toa bool) int64 {
		service := l4forward.NewService(l4forward.NewStore(pool))
		actor := l4forward.Actor{ScopeID: scopeID, UserID: userID, ScopeKind: "tenant"}
		fields := l4forward.Fields{PackageSubscriptionID: new(subscriptionID),
			Name: "toa", Protocol: "tcp", ListenAddress: "*", ListenPort: 18443,
			UpstreamAddress: "8.8.8.8", UpstreamPort: 443, ConnectTimeoutMS: 1000,
			ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, Enabled: true, TOA: toa}
		var result l4forward.WriteResult
		var err error
		if streamID == uuid.Nil {
			result, err = service.Create(t.Context(), actor, l4forward.CreateRequest{Fields: fields,
				IdempotencyKey: "l4-toa-create", RequestID: uuid.NewString()})
		} else {
			result, err = service.Update(t.Context(), actor, l4forward.UpdateRequest{ID: streamID, Fields: fields,
				ExpectedRevision: revision, IdempotencyKey: "l4-toa-update", RequestID: uuid.NewString()})
		}
		if err != nil {
			t.Fatal(err)
		}
		if result.Forward.TOA != toa {
			t.Fatalf("stored toa = %+v", result.Forward)
		}
		streamID, revision = result.Forward.ID, result.Forward.Revision
		return result.Forward.PublishIntent.ConfigurationSourceRevision
	})
}

func TestL4SessionLogReachesPublishedStreams(t *testing.T) {
	var streamID uuid.UUID
	var revision int64
	edgepublish.CheckL4SessionLogPublication(t, func(pool *pgxpool.Pool, scopeID, userID, subscriptionID, siteID uuid.UUID, enabled bool) int64 {
		service := l4forward.NewService(l4forward.NewStore(pool))
		actor := l4forward.Actor{ScopeID: scopeID, UserID: userID, ScopeKind: "tenant"}
		fields := l4forward.Fields{PackageSubscriptionID: new(subscriptionID),
			Name: "log", Protocol: "tcp", ListenAddress: "*", ListenPort: 18443,
			UpstreamAddress: "8.8.8.8", UpstreamPort: 443, ConnectTimeoutMS: 1000,
			ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, Enabled: true, SessionLogEnabled: enabled}
		var result l4forward.WriteResult
		var err error
		if streamID == uuid.Nil {
			result, err = service.Create(t.Context(), actor, l4forward.CreateRequest{Fields: fields,
				IdempotencyKey: "l4-session-log-create", RequestID: uuid.NewString()})
		} else {
			result, err = service.Update(t.Context(), actor, l4forward.UpdateRequest{ID: streamID, Fields: fields,
				ExpectedRevision: revision, IdempotencyKey: "l4-session-log-update", RequestID: uuid.NewString()})
		}
		if err != nil {
			t.Fatal(err)
		}
		if result.Forward.SessionLogEnabled != enabled {
			t.Fatalf("stored session log = %+v", result.Forward)
		}
		streamID, revision = result.Forward.ID, result.Forward.Revision
		return result.Forward.PublishIntent.ConfigurationSourceRevision
	})
}

func TestL4GuardRulesReachPublishedStreams(t *testing.T) {
	var streamID uuid.UUID
	var revision int64
	edgepublish.CheckL4GuardRulesPublication(t, func(pool *pgxpool.Pool, scopeID, userID, subscriptionID, siteID uuid.UUID, rules []edgeconfig.L4GuardRuleV2) int64 {
		service := l4forward.NewService(l4forward.NewStore(pool))
		actor := l4forward.Actor{ScopeID: scopeID, UserID: userID, ScopeKind: "tenant"}
		fields := l4forward.Fields{PackageSubscriptionID: new(subscriptionID),
			Name: "guard", Protocol: "tcp", ListenAddress: "*", ListenPort: 18443,
			UpstreamAddress: "8.8.8.8", UpstreamPort: 443, ConnectTimeoutMS: 1000,
			ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, Enabled: true, GuardRules: rules}
		var result l4forward.WriteResult
		var err error
		if streamID == uuid.Nil {
			result, err = service.Create(t.Context(), actor, l4forward.CreateRequest{Fields: fields,
				IdempotencyKey: "l4-guard-create", RequestID: uuid.NewString()})
		} else {
			result, err = service.Update(t.Context(), actor, l4forward.UpdateRequest{ID: streamID, Fields: fields,
				ExpectedRevision: revision, IdempotencyKey: "l4-guard-update-" + uuid.NewString(), RequestID: uuid.NewString()})
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Forward.GuardRules) != len(rules) {
			t.Fatalf("stored guard rules = %+v", result.Forward.GuardRules)
		}
		streamID, revision = result.Forward.ID, result.Forward.Revision
		return result.Forward.PublishIntent.ConfigurationSourceRevision
	})
}
