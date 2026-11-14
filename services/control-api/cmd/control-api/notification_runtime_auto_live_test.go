package main

import (
	"context"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
)

type autoTestDispatcher struct {
	notification.AnonymousDispatcher
}

// The auto runtime stands in for a worker that may not exist yet: offered
// channels follow its current configuration, recovery mail without a worker
// is a temporary failure (the outbox retries), and dispatchers are kept to be
// registered on the next worker.
func TestNotificationAutoRuntimeWithoutWorker(t *testing.T) {
	startup := notificationRuntimeConfig{Requested: true, Auto: true, Enabled: true, EmailProvider: notificationEmailProviderSMTPTLS}
	auto := newNotificationAutoRuntime(notificationRuntimeConfig{Requested: true, Auto: true}, startup, config.Config{}, nil,
		notificationRuntimeDependencies{})
	if transports := auto.Transports(); !transports.Email || transports.SMS {
		t.Fatalf("transports = %+v", transports)
	}
	auto.config = notificationRuntimeConfig{Requested: true, Auto: true}
	if auto.Transports().Email {
		t.Fatal("transports did not follow the rebuilt configuration")
	}
	if err := auto.Ready(t.Context(), notification.ChannelSwitches{Email: true}); err != notificationruntime.ErrWorkerNotRunning {
		t.Fatalf("Ready without worker = %v", err)
	}
	result := auto.RecoverySender().SendRecovery(t.Context(), accountrecovery.RecoveryDelivery{})
	if result.Failure == nil || result.Failure.Class != notification.FailureTemporary {
		t.Fatalf("recovery without worker = %+v", result)
	}
	registration, err := auto.RegisterAnonymousDispatcher(t.Context(), autoTestDispatcher{})
	if err != nil || len(auto.dispatchers) != 1 {
		t.Fatalf("register = (%v, %v) kept %d", registration, err, len(auto.dispatchers))
	}
	if err := registration.Close(context.Background()); err != nil || len(auto.dispatchers) != 0 {
		t.Fatalf("close = %v kept %d", err, len(auto.dispatchers))
	}
}
