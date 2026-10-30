package certificatepublish

import (
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
)

// 卡 2-B：续签下发失败按指数退避重试，封顶 RetryMaximum。
func TestRenewalDeliveryRetryDelayBacksOffToTheMaximum(t *testing.T) {
	deliverer := &RenewalDeliverer{config: RenewalDelivererConfig{RetryBase: time.Minute, RetryMaximum: 10 * time.Minute}}
	for attempt, want := range map[int]time.Duration{1: time.Minute, 2: 2 * time.Minute, 3: 4 * time.Minute,
		4: 8 * time.Minute, 5: 10 * time.Minute, 30: 10 * time.Minute} {
		if got := deliverer.retryDelay(attempt); got != want {
			t.Errorf("attempt %d: delay %s, want %s", attempt, got, want)
		}
	}
}

// 只向具备原子发布 + 预检能力的节点下发新版本私钥（与用户发布路径同一门槛）。
func TestRenewalNodeCapableRequiresCertificatePublicationCapabilities(t *testing.T) {
	required := edgeautopublish.CertificatePublicationCapabilities()
	full := &agentv1.AgentCapabilities{Features: []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 2},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
	}}
	partial := &agentv1.AgentCapabilities{Features: []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
	}}
	if !renewalNodeCapable(full, required) {
		t.Fatal("capable node refused")
	}
	if renewalNodeCapable(partial, required) || renewalNodeCapable(nil, required) {
		t.Fatal("node without CONFIG_PRECHECK accepted")
	}
}

func TestNewRenewalDelivererRejectsUnusableConfig(t *testing.T) {
	config := DefaultRenewalDelivererConfig()
	config.MaxAttempts = 0
	if _, err := NewRenewalDeliverer(nil, nil, nil, nil, nil, nil, nil, config, time.Now); err == nil {
		t.Fatal("deliverer without dependencies accepted")
	}
	if got := DefaultRenewalDelivererConfig(); got.RetryBase <= 0 || got.RetryMaximum < got.RetryBase ||
		got.MaxAttempts < 1 || got.RoundTimeout < time.Minute {
		t.Fatalf("default config unusable: %+v", got)
	}
}
