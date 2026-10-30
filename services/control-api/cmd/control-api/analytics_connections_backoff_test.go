package main

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnections"
)

func TestAnalyticsConnectionsBackoffFitsDeliveryBudget(t *testing.T) {
	config := analyticsConnectionsConsumerConfig(analyticsconnections.RuntimeConfig{
		Durable: "control_api_connections", Subject: analyticsconnections.ConnectionsSubject,
		OperationTimeout: 5 * time.Second,
	})
	if config.MaxDeliver != 8 || len(config.BackOff) >= config.MaxDeliver {
		t.Fatalf("NATS requires backoff entries < max deliver: entries=%d max=%d", len(config.BackOff), config.MaxDeliver)
	}
	if len(config.BackOff) != 7 || config.BackOff[0] != config.AckWait || config.BackOff[6] != 30*time.Minute {
		t.Fatalf("unexpected connection retry policy: %v", config.BackOff)
	}
}
