package notification

func DecideChannels(policy DeliveryPolicy, switches ChannelSwitches, subscription Subscription) ([]Channel, error) {
	var useSubscription bool
	switch policy {
	case DeliveryTenantSubscribed:
		useSubscription = true
	case DeliverySystemRequired:
		useSubscription = false
	default:
		return nil, ErrInvalidPolicy
	}

	channels := make([]Channel, 0, 2)
	if switches.SMS && (!useSubscription || subscription.SMS) {
		channels = append(channels, ChannelSMS)
	}
	if switches.Email && (!useSubscription || subscription.Email) {
		channels = append(channels, ChannelEmail)
	}
	return channels, nil
}
