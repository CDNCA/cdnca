package controlupgrade

import "testing"

type pubAckStatusDelivery struct {
	*fakeStatusDelivery
	stream   string
	consumer string
	sequence uint64
}

func (delivery *pubAckStatusDelivery) Stream() string         { return delivery.stream }
func (delivery *pubAckStatusDelivery) Consumer() string       { return delivery.consumer }
func (delivery *pubAckStatusDelivery) StreamSequence() uint64 { return delivery.sequence }

func TestDecodeRolloutStatusDeliveryBindsExactBrokerIdentity(t *testing.T) {
	base := exactStatusDelivery()
	delivery := &pubAckStatusDelivery{fakeStatusDelivery: base, stream: upgradeStatusStream,
		consumer: "control_api_upgrade_status", sequence: 41}
	receipt, reason := decodeRolloutStatusDelivery(delivery, DefaultStatusRuntimeConfig())
	if reason != "" || receipt.DeliveryStream != delivery.stream ||
		receipt.DeliveryConsumer != delivery.consumer || receipt.DeliverySequence != delivery.sequence {
		t.Fatalf("broker-bound receipt = (%#v,%q)", receipt, reason)
	}

	for name, mutate := range map[string]func(*pubAckStatusDelivery){
		"stream":   func(value *pubAckStatusDelivery) { value.stream = "OTHER" },
		"consumer": func(value *pubAckStatusDelivery) { value.consumer = "other_consumer" },
		"sequence": func(value *pubAckStatusDelivery) { value.sequence = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := *delivery
			mutate(&candidate)
			if _, got := decodeRolloutStatusDelivery(&candidate, DefaultStatusRuntimeConfig()); got != "broker_identity" {
				t.Fatalf("broker mismatch reason = %q", got)
			}
		})
	}
}
