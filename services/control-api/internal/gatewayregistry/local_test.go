package gatewayregistry

import (
	"testing"
	"time"
)

// what the co-located Gateway
// last presented, and whether that is recent.
func TestLocalGatewayStatus(t *testing.T) {
	now := time.Date(2026, 11, 24, 8, 0, 0, 0, time.UTC)
	service := &Service{config: Config{Now: func() time.Time { return now }, LocalGateway: Entrypoint{Address: "gw.example.com:9444", ServerName: "gw.example.com"}}}
	if got := service.localGateway(0); got.Status != "not_reported" || got.LastSeenAt != nil || got.Address != "gw.example.com:9444" {
		t.Fatalf("before any call = %+v", got)
	}
	notAfter := now.Add(90 * 24 * time.Hour)
	service.ObserveLocalGateway("6cfad302-0e27-44c0-b37f-3b4f5ad4c08b", "", notAfter)
	service.ObserveLocalGateway("6cfad302-0e27-44c0-b37f-3b4f5ad4c08b", "1.0.35", time.Time{})
	got := service.localGateway(3)
	if got.Status != "online" || got.Version != "1.0.35" || got.ReadyAt == nil || !got.CertificateExpiresAt.Equal(notAfter) ||
		got.NodesOnline != 3 || got.InstanceID != "6cfad302-0e27-44c0-b37f-3b4f5ad4c08b" {
		t.Fatalf("after ready = %+v", got)
	}
	// A later call without a version keeps the version and certificate.
	now = now.Add(time.Minute)
	service.ObserveLocalGateway("", "", time.Time{})
	if got := service.localGateway(0); got.Version != "1.0.35" || got.CertificateExpiresAt == nil || !got.LastSeenAt.Equal(now) {
		t.Fatalf("after a plain call = %+v", got)
	}
	now = now.Add(LocalGatewayFresh + time.Second)
	if got := service.localGateway(0); got.Status != "offline" {
		t.Fatalf("silent past the window = %+v", got)
	}
	var none *Service
	none.ObserveLocalGateway("x", "y", now) // a disabled registry ignores observations
}
