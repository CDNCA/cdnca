//go:build integration

package edgepublish_test

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestL4AdditionalListenerRealPublicationLifecycle(t *testing.T) {
	edgepublish.CheckL4AdditionalListenerPublication(t, func(pool *pgxpool.Pool, scope, user, subscription, site uuid.UUID) []func() int64 {
		service := l4forward.NewService(l4forward.NewStore(pool))
		actor := l4forward.Actor{ScopeID: scope, UserID: user, ScopeKind: "tenant"}
		fields := l4forward.Fields{PackageSubscriptionID: new(subscription), Name: "additional lifecycle", Protocol: "tcp", ListenAddress: "*", ListenPort: 19443, UpstreamAddress: "8.8.8.8", UpstreamPort: 443, ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, Enabled: true}
		var current l4forward.Forward
		update := func(key string) int64 {
			result, err := service.Update(t.Context(), actor, l4forward.UpdateRequest{ID: current.ID, ExpectedRevision: current.Revision, Fields: fields, IdempotencyKey: key, RequestID: uuid.NewString()})
			if err != nil {
				t.Fatal(err)
			}
			current = result.Forward
			return current.PublishIntent.ConfigurationSourceRevision
		}
		return []func() int64{
			func() int64 {
				result, err := service.Create(t.Context(), actor, l4forward.CreateRequest{Fields: fields, IdempotencyKey: "additional-create", RequestID: uuid.NewString()})
				if err != nil {
					t.Fatal(err)
				}
				current = result.Forward
				return current.PublishIntent.ConfigurationSourceRevision
			},
			func() int64 {
				listeners := []l4forward.AdditionalListener{{ID: uuid.New(), Protocol: "udp", Address: "*", Port: 19444}}
				fields.AdditionalListeners = &listeners
				return update("additional-add")
			},
			func() int64 {
				empty := []l4forward.AdditionalListener{}
				fields.AdditionalListeners = &empty
				return update("additional-clear")
			},
			func() int64 { fields.Enabled = false; return update("additional-disable") },
			func() int64 {
				result, err := service.Delete(t.Context(), actor, l4forward.DeleteRequest{ID: current.ID, ExpectedRevision: current.Revision, IdempotencyKey: "additional-delete", RequestID: uuid.NewString()})
				if err != nil {
					t.Fatal(err)
				}
				return result.PublishIntent.ConfigurationSourceRevision
			},
		}
	})
}

func TestL4AdditionalListenerRealPublicationRejectsHealthPort(t *testing.T) {
	edgepublish.CheckL4AdditionalListenerHealthPort(t, func(pool *pgxpool.Pool, scope, user, subscription, site uuid.UUID, healthPort uint16) {
		listeners := []l4forward.AdditionalListener{{ID: uuid.New(), Protocol: "tcp", Address: "*", Port: healthPort}}
		_, err := l4forward.NewService(l4forward.NewStore(pool)).Create(t.Context(), l4forward.Actor{ScopeID: scope, UserID: user, ScopeKind: "tenant"}, l4forward.CreateRequest{
			Fields: l4forward.Fields{PackageSubscriptionID: new(subscription), Name: "health conflict", Protocol: "tcp", ListenAddress: "*", ListenPort: 19443, AdditionalListeners: &listeners, UpstreamAddress: "8.8.8.8", UpstreamPort: 443, ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, Enabled: true}, IdempotencyKey: "additional-health", RequestID: uuid.NewString(),
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}
